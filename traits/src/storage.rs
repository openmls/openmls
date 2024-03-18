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

use crate::types::{HpkeKeyPair, HpkePrivateKey};

use self::kv::KeyValueStore;

/// Key is returned in errors, to indicate which field the request failed on.
#[derive(Clone, Debug)]
pub enum Key {
    KeyPackage(KeyPackageRef),
    EncryptionKey(HpkePublicKey),
    InitKey(HpkePublicKey),
}

/// GetError indicates a failed get query
#[derive(Clone, Debug)]
pub enum GetError<InnerError> {
    InternalError(InnerError),
    NotFound(Key),
}

/// DeleteError indicates a failed delete query
#[derive(Clone, Debug)]
pub enum DeleteError<InnerError> {
    InternalError(InnerError),
    NotFound(Key),
}

/// InsertError indicates a failed insert query
#[derive(Clone, Debug)]
pub enum InsertError<InnerError> {
    InternalError(InnerError),
    AlreadyExists(Key),
}

// a few key types
// TODO: document

#[derive(Clone, Debug)]
pub struct PskBundleId(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct EpochKeyPairId(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct KeyPackageRef(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct HpkePublicKey(Vec<u8>);

// a few value types
// TODO: document

#[derive(Clone, Debug)]
pub struct PskBundle(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct KeyPackage(pub Vec<u8>);

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
    pub enum InsertError<'a, InnerError> {
        InternalError(InnerError),
        AlreadyExists(&'a [u8]),
    }

    pub trait KeyValueStore {
        type Error;

        fn get(&mut self, key: &[u8]) -> GetError<Self::Error>;
        fn insert(&mut self, key: &[u8], value: &[u8]) -> InsertError<Self::Error>;
        fn delete(&mut self, key: &[u8]) -> DeleteError<Self::Error>;
    }
}

// This trait is more of an interface documentation. I am not convinced it needs to be a trait,
// it might be fine to just have this as a struct that implements these methods.
/// Storage provides the high-level interface to OpenMLS. A version describes a certain layout of
/// data inside the key-value store.
pub trait Storage<KvStore: KeyValueStore> {
    fn new(kv: KvStore) -> Self;

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
        public_key: &HpkePublicKey,
    ) -> Result<HpkePrivateKey, GetError<KvStore::Error>>;

    fn insert_encryption_secret_key(
        &self,
        public_key: &HpkePublicKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn delete_encryption_secret_key(
        &mut self,
        public_key: &HpkePublicKey,
    ) -> Result<(), DeleteError<KvStore::Error>>;

    // ---

    fn get_init_secret_key(
        &self,
        public_key: &HpkePublicKey,
    ) -> Result<HpkePrivateKey, GetError<KvStore::Error>>;

    fn insert_init_secret_key(
        &mut self,
        public_key: &HpkePublicKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::Error>>;

    fn delete_init_secret_key(
        &mut self,
        public_key: &HpkePublicKey,
    ) -> Result<(), GetError<KvStore::Error>>;

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
        &self,
        id: &PskBundleId,
        bundle: PskBundle,
    ) -> Result<(), InsertError<KvStore::Error>>;
    fn delete_psk_bundle(&mut self, id: &PskBundleId) -> Result<(), GetError<KvStore::Error>>;

    // ---

    fn get_mls_group(&self, group_id: &[u8]) -> Result<Vec<u8>, GetError<KvStore::Error>>;
    fn insert_mls_group(
        &self,
        group_id: &[u8],
        group: Vec<u8>,
    ) -> Result<(), InsertError<KvStore::Error>>;
    fn delete_mls_group(&mut self, group_id: &[u8]) -> Result<(), GetError<KvStore::Error>>;
}

/// MigrationV1V2Error explains why a migration from version 1 to version 2 failed.
#[derive(Clone, Debug)]
pub enum MigrationV1V2Error<InnerError> {
    InternalError(InnerError),
}

// an example for how we could implement migrations
trait StorageV2<KvStore: KeyValueStore>: Storage<KvStore> {
    fn migrate_v1_v2(kv: KvStore) -> Result<(), MigrationV1V2Error<KvStore::Error>>;
}
