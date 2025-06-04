//! A provider for benchmarking.
//! This always persists things so that we can prepare groups for benchmarks
//! and don't have to redo them every time.

use openmls::test_utils::OpenMlsLibcrux;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;

pub type Provider = OpenMlsRustCrypto; // OpenMlsLibcrux | 2x slower

// #[derive(Default)]
// pub struct BinCodec;

// impl Codec for BinCodec {
//     type Error = bitcode::Error;

//     fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
//         bitcode::serialize(value)
//     }

//     fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
//         bitcode::deserialize(slice)
//     }
// }

// pub struct Provider {
//     crypto: CryptoProvider,
//     storage: SqliteStorageProvider<BinCodec, Connection>,
// }

// impl Default for Provider {
//     fn default() -> Self {
//         let connection = Connection::open("group.db").unwrap();
//         let mut storage = SqliteStorageProvider::new(connection);
//         storage.initialize().unwrap();

//         Self {
//             crypto: CryptoProvider::new().unwrap(),
//             storage,
//         }
//     }
// }

// impl Provider {
//     pub fn new(path: &str) -> Self {
//         let connection = Connection::open(path).unwrap();
//         let mut storage = SqliteStorageProvider::new(connection);
//         storage.initialize().unwrap();

//         Self {
//             crypto: CryptoProvider::new().unwrap(),
//             storage,
//         }
//     }
// }

// impl OpenMlsProvider for Provider {
//     type CryptoProvider = CryptoProvider;
//     type RandProvider = CryptoProvider;
//     type StorageProvider = SqliteStorageProvider<BinCodec, Connection>;

//     fn storage(&self) -> &Self::StorageProvider {
//         &self.storage
//     }

//     fn crypto(&self) -> &Self::CryptoProvider {
//         &self.crypto
//     }

//     fn rand(&self) -> &Self::RandProvider {
//         &self.crypto
//     }
// }
