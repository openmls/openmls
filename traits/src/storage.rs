//! This module defines an experimental storage trait. It follows a different design philosophy
//! than the current version: instead of providing a highly generic abstraction over a key-value
//! store, we provide a high-level interface for the specific queries made by OpenMLS.
//!
//! To explain the reasoning behind this, consider the current stack of abstractions:
//!
//!      OpenMLS
//!   ------------ typed kv store
//!     Keystore
//!   ------------ ????
//!       ???
//!
//! This model still provides a relatively low-level API to OpenMLS, and OpenMLS can still
//! inadvertantly change the data it stores in the Keystore, which endangers versioning. At the
//! same time, since the trait does not define how the key store is backed, it can not make any
//! guarantees of stability - it does not even have the vocabulary.
//!
//! So we need to do two things: We need to define the abstraction we are building on top of, and
//! we need to define the interface we offer to OpenMLS, such that it has versions and a way to
//! migrate between versions. Since one important target environment that OpenMLS is supposed to
//! run in is the web, we need to work with what we have there, and that is LocalStorage: A
//! key-value store without transactions.
//!
//! The higher level trait is not constrained to be generic. It can be as specific to OpenMLS's use
//! case as is useful. This means the storage provider can ideally take care of marshalling and
//! bookkeeping such as "when removing a key package, also remove the secrets". This way, the
//! new stack of abstractions is:
//!
//!       OpenMLS
//!  ----------------- high-level storage API
//!       Storage
//!  ----------------- Get/Insert/Delete
//!    KeyValueStore
//!
//! One problem this design currently has is that while we would ideally offer a high-level API,
//! we can't consume or return domain types such as KeyPackage, because those are defined in the
//! `openmls` crate, which we can't import because that would be a cyclic dependency. Currently we
//! just consume and produce bytes, which the caller has to de/serialize.
//!
//! One way to address this is to move these types to a crate `openmls-types`, that does not have
//! any dependencies on other OpenMLS crates, such that we can import it both here and in
//! `openmls`. Another upside of that would be that changes to OpenMLS are a lot less likely to
//! break versioning, and that a lot more care has to be taken when editing the `openmls-types`
//! crate. Maybe that makes development easier.
//!
//! On the other hand, this would be a pretty large refactor, and it's not clear if that is worth
//! the effort. If we don't think so, we can still do de/serialization inside OpenMLS.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::types::{HpkeKeyPair, HpkePrivateKey};

const MAX_SUPPORTED_VERSION: u16 = 1;

/// Key is returned in errors, to indicate which field the request failed on.
#[derive(Clone, Debug)]
pub enum Key {
    EpochKeyPair(EpochKeyPairId),
    PskBundle(PskBundleId),
    KeyPackage(KeyPackageRef),
    EncryptionKey(EncryptionKey),
    InitKey(InitKey),
    Group(GroupId),
}

impl From<EpochKeyPairId> for Key {
    fn from(value: EpochKeyPairId) -> Self {
        Key::EpochKeyPair(value)
    }
}

impl From<KeyPackageRef> for Key {
    fn from(value: KeyPackageRef) -> Self {
        Key::KeyPackage(value)
    }
}

impl From<EncryptionKey> for Key {
    fn from(value: EncryptionKey) -> Self {
        Key::EncryptionKey(value)
    }
}

impl From<InitKey> for Key {
    fn from(value: InitKey) -> Self {
        Key::InitKey(value)
    }
}

impl From<PskBundleId> for Key {
    fn from(value: PskBundleId) -> Self {
        Key::PskBundle(value)
    }
}

impl From<GroupId> for Key {
    fn from(value: GroupId) -> Self {
        Key::Group(value)
    }
}

/// CreateError indicates that creating a new Storage failed
#[derive(Debug)]
pub enum CreateError<InnerError> {
    InternalError(InnerError),
    UnsupportedVersion(u16),
    AlreadyCreated,
}

/// OpenError indicates that opening a Storage failed
#[derive(Debug)]
pub enum OpenError<InnerError> {
    InternalError(InnerError),
    UnsupportedVersion(u16),
    InvalidFormat,
}

/// GetError indicates a failed get query
#[derive(Debug)]
pub enum GetError<InnerError> {
    InternalError(InnerError),
    #[cfg(test)]
    DeserializeFailed(serde_json::Error),
    NotFound(Key),
}

impl<T> GetError<T> {
    pub fn from_kv_error(key: Key) -> impl (FnOnce(kv::GetError<T>) -> Self) {
        move |kv_err| match kv_err {
            kv::GetError::InternalError(e) => Self::InternalError(e),
            kv::GetError::NotFound(_) => Self::NotFound(key),
        }
    }
}

/// DeleteError indicates a failed delete query
#[derive(Debug)]
pub enum DeleteError<InnerError> {
    InternalError(InnerError),
    NotFound(Key),
    GetKeyPackageError(GetError<InnerError>),
}

impl<T> DeleteError<T> {
    pub fn from_kv_error(key: Key) -> impl (FnOnce(kv::DeleteError<T>) -> Self) {
        move |kv_err| match kv_err {
            kv::DeleteError::InternalError(e) => Self::InternalError(e),
            kv::DeleteError::NotFound(_) => Self::NotFound(key),
        }
    }
}

/// InsertError indicates a failed insert query
#[derive(Debug)]
pub enum InsertError<InnerError> {
    InternalError(InnerError),
    AlreadyExists(Key),
    #[cfg(test)]
    SerializeFailed(serde_json::Error),
}

impl<T> InsertError<T> {
    pub fn from_kv_error(key: Key) -> impl (FnOnce(kv::InsertError<T>) -> Self) {
        move |kv_err| match kv_err {
            kv::InsertError::InternalError(e) => Self::InternalError(e),
            kv::InsertError::AlreadyExists(_) => Self::AlreadyExists(key),
        }
    }
}

// a few key types

// TODO:
//  - document the structs
//  - use numbers for domain separating keys
//  - also domain separate ciphersuites, maybe?

#[derive(Clone, Debug)]
pub struct GroupId(pub Vec<u8>);

impl GroupId {
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(6 + self.0.len());
        write!(&mut key, "group/").unwrap();
        key.write_all(&self.0).unwrap();
        key
    }
}

#[derive(Clone, Debug)]
pub struct PskBundleId(pub Vec<u8>);

impl PskBundleId {
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(10 + self.0.len());
        write!(&mut key, "pskbundle/").unwrap();
        key.write_all(&self.0).unwrap();
        key
    }
}

#[derive(Clone, Debug)]
pub struct EpochKeyPairId(pub Vec<u8>);

impl EpochKeyPairId {
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(13 + self.0.len());
        write!(&mut key, "epochkeypair/").unwrap();
        key.write_all(&self.0).unwrap();
        key
    }
}

#[derive(Clone, Debug)]
pub struct KeyPackageRef(pub Vec<u8>);

impl KeyPackageRef {
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(11 + self.0.len());
        write!(&mut key, "keypackage/").unwrap();
        key.write_all(&self.0).unwrap();
        key
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionKey(Vec<u8>);

impl EncryptionKey {
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(14 + self.0.len());
        write!(&mut key, "encryptionkey/").unwrap();
        key.write_all(&self.0).unwrap();
        key
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitKey(Vec<u8>);

impl InitKey {
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + self.0.len());
        write!(&mut key, "initkey/").unwrap();
        key.write_all(&self.0).unwrap();
        key
    }
}

// a few value types
// TODO: document

#[derive(Clone, Debug)]
pub struct PskBundle(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackage {
    serialized: Vec<u8>,
    encryption_key: EncryptionKey,
    init_key: InitKey,
}

/// The kv module describes the underlying byte-oriented Key Value Store
pub mod kv {
    #[derive(Clone, Debug)]
    pub enum GetError<'a, InnerError> {
        InternalError(InnerError),
        NotFound(&'a [u8]),
    }

    #[derive(Clone, Debug)]
    pub enum DeleteError<'a, InnerError> {
        InternalError(InnerError),
        NotFound(&'a [u8]),
    }

    #[derive(Clone, Debug)]
    pub enum InsertError<InnerError> {
        InternalError(InnerError),
        AlreadyExists(Vec<u8>),
    }

    pub trait KeyValueStore {
        type Error: std::fmt::Debug;

        fn get<'a>(&self, key: &'a [u8]) -> Result<Vec<u8>, GetError<'a, Self::Error>>;
        fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), InsertError<Self::Error>>;
        fn delete<'a>(&mut self, key: &'a [u8]) -> Result<(), DeleteError<'a, Self::Error>>;
    }

    #[cfg(test)]
    use std::collections::HashMap;

    #[cfg(test)]
    impl KeyValueStore for HashMap<Vec<u8>, Vec<u8>> {
        type Error = ();

        fn get<'a>(&self, key: &'a [u8]) -> Result<Vec<u8>, GetError<'a, Self::Error>> {
            HashMap::get(self, key)
                .ok_or(GetError::NotFound(key))
                .cloned()
        }

        fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), InsertError<Self::Error>> {
            match HashMap::insert(self, key.clone(), value) {
                Some(old_value) => {
                    HashMap::insert(self, key.clone(), old_value);
                    Err(InsertError::AlreadyExists(key))
                }
                None => Ok(()),
            }
        }

        fn delete<'a>(&mut self, key: &'a [u8]) -> Result<(), DeleteError<'a, Self::Error>> {
            HashMap::remove(self, key)
                .ok_or(DeleteError::NotFound(key))
                .map(|_| ())
        }
    }
}

// This trait is more of an interface documentation. I am not convinced it needs to be a trait,
// it might be fine to just have this as a struct that implements these methods.
/// Storage provides the high-level interface to OpenMLS. A version describes a certain layout of
/// data inside the key-value store.
pub trait Storage<KvStore: KeyValueStore> {
    /// returns the version of the data currently stored in the KVStore
    fn current_version(&self) -> u16;

    fn get_epoch_key_pairs(
        &self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<Vec<HpkeKeyPair>, GetError<KvStore::Error>>;

    fn insert_epoch_key_pairs(
        &mut self,
        epoch_key_pair_id: &EpochKeyPairId,
        key_pairs: Vec<HpkeKeyPair>,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn delete_epoch_key_pairs(
        &mut self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<(), DeleteError<KvStore::Error>>;

    // ---

    fn get_encryption_secret_key(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<HpkePrivateKey, GetError<KvStore::Error>>;

    fn insert_encryption_secret_key(
        &mut self,
        public_key: &EncryptionKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn delete_encryption_secret_key(
        &mut self,
        public_key: &EncryptionKey,
    ) -> Result<(), DeleteError<KvStore::Error>>;

    // ---

    fn get_init_secret_key(
        &self,
        public_key: &InitKey,
    ) -> Result<HpkePrivateKey, GetError<KvStore::Error>>;

    fn insert_init_secret_key(
        &mut self,
        public_key: &InitKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn delete_init_secret_key(
        &mut self,
        public_key: &InitKey,
    ) -> Result<(), DeleteError<KvStore::Error>>;

    // ---

    // Also deletes secret keys
    fn delete_key_package(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<(), DeleteError<KvStore::Error>>;

    fn get_key_package(
        &self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<KeyPackage, GetError<KvStore::Error>>;

    fn insert_key_package(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn insert_key_package_with_keys(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
        init_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn insert_key_package_with_encryption_key(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn insert_key_package_with_init_key(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        init_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    // ---

    fn get_psk_bundle(&self, id: &PskBundleId) -> Result<PskBundle, GetError<KvStore::Error>>;
    fn insert_psk_bundle(
        &mut self,
        id: &PskBundleId,
        bundle: PskBundle,
    ) -> Result<(), InsertError<KvStore::Error>>;
    fn delete_psk_bundle(&mut self, id: &PskBundleId) -> Result<(), DeleteError<KvStore::Error>>;

    // ---

    fn get_mls_group(&self, group_id: &GroupId) -> Result<Vec<u8>, GetError<KvStore::Error>>;
    fn insert_mls_group(
        &mut self,
        group_id: &GroupId,
        group: Vec<u8>,
    ) -> Result<(), InsertError<KvStore::Error>>;
    fn delete_mls_group(&mut self, group_id: &GroupId) -> Result<(), DeleteError<KvStore::Error>>;
}

/// MigrationV1V2Error explains why a migration from version 1 to version 2 failed.
#[derive(Clone, Debug)]
pub enum MigrationV1V2Error<InnerError> {
    InternalError(InnerError),
}

use self::kv::KeyValueStore;

// an example for how we could implement migrations
trait StorageV2<KvStore: KeyValueStore>: Storage<KvStore> {
    fn migrate_v1_v2(kv: KvStore) -> Result<(), MigrationV1V2Error<KvStore::Error>>;
}

struct KvStoreStorage<KvStore: KeyValueStore>(KvStore);

impl<KvStore: KeyValueStore> KvStoreStorage<KvStore> {
    fn open(kv: KvStore) -> Result<Self, OpenError<KvStore::Error>> {
        match kv.get(b"version") {
            Ok(version_byte_vec) => {
                let version_bytes: [u8; 2] = version_byte_vec
                    .try_into()
                    .map_err(|_| OpenError::InvalidFormat)?;
                let version = u16::from_be_bytes(version_bytes);
                if version > MAX_SUPPORTED_VERSION {
                    Err(OpenError::UnsupportedVersion(version))
                } else {
                    Ok(Self(kv))
                }
            }
            Err(kv::GetError::InternalError(e)) => Err(OpenError::InternalError(e)),
            Err(kv::GetError::NotFound(_)) => Err(OpenError::InvalidFormat),
        }
    }

    fn create(mut kv: KvStore) -> Result<Self, CreateError<KvStore::Error>> {
        match kv.insert(
            b"version".to_vec(),
            MAX_SUPPORTED_VERSION.to_be_bytes().to_vec(),
        ) {
            Ok(_) => Ok(Self(kv)),
            Err(e) => match e {
                kv::InsertError::InternalError(e) => Err(CreateError::InternalError(e)),
                kv::InsertError::AlreadyExists(_) => Err(CreateError::AlreadyCreated),
            },
        }
    }
}

#[cfg(test)]
impl<KvStore: KeyValueStore> Storage<KvStore> for KvStoreStorage<KvStore> {
    fn current_version(&self) -> u16 {
        let version_bytes: [u8; 2] = self.0.get(b"version").unwrap().try_into().unwrap();
        u16::from_be_bytes(version_bytes)
    }

    fn get_epoch_key_pairs(
        &self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<Vec<HpkeKeyPair>, GetError<<KvStore as KeyValueStore>::Error>> {
        let key = epoch_key_pair_id.key();
        let value_bytes = self
            .0
            .get(&key)
            .map_err(GetError::from_kv_error(epoch_key_pair_id.clone().into()))?;
        serde_json::from_slice(&value_bytes).map_err(GetError::DeserializeFailed)
    }

    fn insert_epoch_key_pairs(
        &mut self,
        epoch_key_pair_id: &EpochKeyPairId,
        key_pairs: Vec<HpkeKeyPair>,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        let key = epoch_key_pair_id.key();
        let value_bytes = serde_json::to_vec(&key_pairs).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key, value_bytes)
            .map_err(InsertError::from_kv_error(epoch_key_pair_id.clone().into()))
    }

    fn delete_epoch_key_pairs(
        &mut self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<(), DeleteError<<KvStore as KeyValueStore>::Error>> {
        let key = epoch_key_pair_id.key();
        self.0
            .delete(&key)
            .map_err(DeleteError::from_kv_error(epoch_key_pair_id.clone().into()))
    }

    fn get_encryption_secret_key(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<HpkePrivateKey, GetError<<KvStore as KeyValueStore>::Error>> {
        let key = public_key.key();
        let value_bytes = self
            .0
            .get(&key)
            .map_err(GetError::from_kv_error(public_key.clone().into()))?;
        serde_json::from_slice(&value_bytes).map_err(GetError::DeserializeFailed)
    }

    fn insert_encryption_secret_key(
        &mut self,
        public_key: &EncryptionKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        let key = public_key.key();
        let value_bytes = serde_json::to_vec(&secret_key).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key, value_bytes)
            .map_err(InsertError::from_kv_error(public_key.clone().into()))
    }

    fn delete_encryption_secret_key(
        &mut self,
        public_key: &EncryptionKey,
    ) -> Result<(), DeleteError<<KvStore as KeyValueStore>::Error>> {
        let key = public_key.key();
        self.0
            .delete(&key)
            .map_err(DeleteError::from_kv_error(public_key.clone().into()))
    }

    fn get_init_secret_key(
        &self,
        public_key: &InitKey,
    ) -> Result<HpkePrivateKey, GetError<<KvStore as KeyValueStore>::Error>> {
        let key = public_key.key();
        let value_bytes = self
            .0
            .get(&key)
            .map_err(GetError::from_kv_error(public_key.clone().into()))?;
        serde_json::from_slice(&value_bytes).map_err(GetError::DeserializeFailed)
    }

    fn insert_init_secret_key(
        &mut self,
        public_key: &InitKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        let key = public_key.key();
        let value_bytes = serde_json::to_vec(&secret_key).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key, value_bytes)
            .map_err(InsertError::from_kv_error(public_key.clone().into()))
    }

    fn delete_init_secret_key(
        &mut self,
        public_key: &InitKey,
    ) -> Result<(), DeleteError<<KvStore as KeyValueStore>::Error>> {
        let key = public_key.key();
        self.0
            .delete(&key)
            .map_err(DeleteError::from_kv_error(public_key.clone().into()))
    }

    fn delete_key_package(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<(), DeleteError<<KvStore as KeyValueStore>::Error>> {
        // fetch the key package before deleting, so we can also delete the secrets
        let key_pkg = self
            .get_key_package(key_pkg_ref)
            .map_err(DeleteError::GetKeyPackageError)?;

        self.0
            .delete(&key_pkg_ref.key())
            .map_err(DeleteError::from_kv_error(key_pkg_ref.clone().into()))?;

        // also delete the secret keys, if they are known
        match self.delete_init_secret_key(&key_pkg.init_key) {
            Err(DeleteError::NotFound(_)) => Ok(()),
            other => other,
        }?;

        match self.delete_encryption_secret_key(&key_pkg.encryption_key) {
            Err(DeleteError::NotFound(_)) => Ok(()),
            other => other,
        }
    }

    fn get_key_package(
        &self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<KeyPackage, GetError<<KvStore as KeyValueStore>::Error>> {
        let key = key_pkg_ref.key();
        let value_bytes = self
            .0
            .get(&key)
            .map_err(GetError::from_kv_error(key_pkg_ref.clone().into()))?;
        serde_json::from_slice(&value_bytes).map_err(GetError::DeserializeFailed)
    }

    fn insert_key_package(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        let key = key_pkg_ref.key();
        let bytes = serde_json::to_vec(&key_pkg).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key_pkg_ref.key(), bytes)
            .map_err(InsertError::from_kv_error(key_pkg_ref.clone().into()))
    }

    fn insert_key_package_with_keys(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
        init_key: HpkePrivateKey,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        self.insert_init_secret_key(&key_pkg.init_key, init_key)?;
        self.insert_encryption_secret_key(&key_pkg.encryption_key, encryption_key)?;
        self.insert_key_package(key_pkg_ref, key_pkg)
    }

    fn insert_key_package_with_encryption_key(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        self.insert_encryption_secret_key(&key_pkg.encryption_key, encryption_key)?;
        self.insert_key_package(key_pkg_ref, key_pkg)
    }

    fn insert_key_package_with_init_key(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        init_key: HpkePrivateKey,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        self.insert_init_secret_key(&key_pkg.init_key, init_key)?;
        self.insert_key_package(key_pkg_ref, key_pkg)
    }

    fn get_psk_bundle(
        &self,
        id: &PskBundleId,
    ) -> Result<PskBundle, GetError<<KvStore as KeyValueStore>::Error>> {
        self.0
            .get(&id.key())
            .map_err(GetError::from_kv_error(id.clone().into()))
            .map(PskBundle)
    }

    fn insert_psk_bundle(
        &mut self,
        id: &PskBundleId,
        bundle: PskBundle,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        self.0
            .insert(id.key(), bundle.0)
            .map_err(InsertError::from_kv_error(id.clone().into()))
    }

    fn delete_psk_bundle(
        &mut self,
        id: &PskBundleId,
    ) -> Result<(), DeleteError<<KvStore as KeyValueStore>::Error>> {
        self.0
            .delete(&id.key())
            .map_err(DeleteError::from_kv_error(id.clone().into()))
    }

    fn get_mls_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, GetError<<KvStore as KeyValueStore>::Error>> {
        self.0
            .get(&group_id.key())
            .map_err(GetError::from_kv_error(group_id.clone().into()))
    }

    fn insert_mls_group(
        &mut self,
        group_id: &GroupId,
        group: Vec<u8>,
    ) -> Result<(), InsertError<<KvStore as KeyValueStore>::Error>> {
        self.0
            .insert(group_id.key(), group)
            .map_err(InsertError::from_kv_error(group_id.clone().into()))
    }

    fn delete_mls_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), DeleteError<<KvStore as KeyValueStore>::Error>> {
        self.0
            .delete(&group_id.key())
            .map_err(DeleteError::from_kv_error(group_id.clone().into()))
    }
}
