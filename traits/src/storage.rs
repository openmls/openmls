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

use serde::{Deserialize, Serialize};
use std::io::Write;

use openmls_spec_types::hpke::{HpkeKeyPair, HpkePrivateKey};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredProposal {
    pub proposal_ref: ProposalRef,
    pub proposal: Proposal,
    pub sender: Sender,
    pub proposal_or_ref_type: ProposalOrRefType,
}

#[derive(Clone, Debug)]
pub enum Update {
    InsertEpochKeyPairs(EpochKeyPairId, Vec<HpkeKeyPair>),
    DeleteEpochKeyPairs(EpochKeyPairId),
    InsertEncryptionSecretKey(EncryptionKey, HpkePrivateKey),
    DeleteEncryptionSecretKey(EncryptionKey),
    InsertInitSecretKey(InitKey, HpkePrivateKey),
    DeleteInitSecretKey(InitKey),
    InsertKeyPackage(KeyPackageRef, KeyPackage),
    InsertKeyPackageWithEncryptionKey(KeyPackageRef, KeyPackage, HpkePrivateKey),
    InsertKeyPackageWithInitKey(KeyPackageRef, KeyPackage, HpkePrivateKey),
    InsertKeyPackageWithKeys {
        key_pkg_ref: KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
        init_key: HpkePrivateKey,
    },
    DeleteKeyPackage(KeyPackageRef),
    InsertPskBundle(PskBundleId, PskBundle),
    DeletePskBundle(PskBundleId),
    QueueProposal(StoredProposal),
    DeleteProposal(ProposalRef),
    ClearProposalQueue,
}

#[derive(Clone, Debug)]
pub struct Updates(pub Vec<Update>);

/// Key is returned in errors, to indicate which field the request failed on.
// TODO: this leaks abstractions.
// we shouldn't care about the mechanism this is stored with.
// maybe just rename it to something else than key? lookup errors can happen regardless of
// mechanism
#[derive(Clone, Debug)]
pub enum Key {
    EpochKeyPair(EpochKeyPairId),
    PskBundle(PskBundleId),
    KeyPackage(KeyPackageRef),
    EncryptionKey(EncryptionKey),
    InitKey(InitKey),
    Group(GroupId),
    Proposal(ProposalRef),
    QueuedProposals,
}

// returned by apply_update
pub enum UpdateError<InternalError, SerializeError> {
    DeleteError(DeleteError<InternalError, SerializeError>),
    InsertError(InsertError<InternalError, SerializeError>),
}

impl<E1, E2> From<InsertError<E1, E2>> for UpdateError<E1, E2> {
    fn from(value: InsertError<E1, E2>) -> Self {
        UpdateError::InsertError(value)
    }
}

impl<E1, E2> From<DeleteError<E1, E2>> for UpdateError<E1, E2> {
    fn from(value: DeleteError<E1, E2>) -> Self {
        UpdateError::DeleteError(value)
    }
}

/// CreateError indicates that creating a new Storage failed
#[derive(Debug)]
pub enum CreateError<InternalError> {
    InternalError(InternalError),
    UnsupportedVersion(u16),
    AlreadyCreated,
}

/// OpenError indicates that opening a Storage failed
#[derive(Debug)]
pub enum OpenError<InternalError> {
    InternalError(InternalError),
    UnsupportedVersion(u16),
    InvalidFormat,
}

/// GetError indicates a failed get query
#[derive(Debug)]
pub enum GetError<InternalError, SerializeError> {
    InternalError(InternalError),
    DeserializeFailed(SerializeError),
    NotFound(Key),
}

/// DeleteError indicates a failed delete query
#[derive(Debug)]
pub enum DeleteError<InternalError, SerializeError> {
    InternalError(InternalError),
    NotFound(Key),
    GetKeyPackageError(GetError<InternalError, SerializeError>),
    GetProposalQueueError(GetError<InternalError, SerializeError>),
}

/// InsertError indicates a failed insert query
#[derive(Debug)]
pub enum InsertError<InternalError, SerializeError> {
    InternalError(InternalError),
    AlreadyExists(Key),
    SerializeFailed(SerializeError),
}

// a few key types

// TODO:
//  - document the structs
//  - use numbers for domain separating keys
//  - also domain separate ciphersuites, maybe?

use openmls_spec_types::proposals::{Proposal, ProposalOrRefType, ProposalRef, Sender};
use openmls_spec_types::GroupId;

#[derive(Clone, Debug)]
pub struct PskBundleId(pub Vec<u8>);

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

use openmls_spec_types::key_package::{KeyPackage, KeyPackageRef};

use openmls_spec_types::keys::EncryptionKey;
use openmls_spec_types::keys::InitKey;

// a few value types
// TODO: document

#[derive(Clone, Debug)]
pub struct PskBundle(pub Vec<u8>);

pub trait Platform {
    type InternalError: core::fmt::Debug;
    type SerializeError: core::fmt::Debug;
}

pub trait Stored<T> {
    fn get(self) -> T;
}

// This trait is more of an interface documentation. I am not convinced it needs to be a trait,
// it might be fine to just have this as a struct that implements these methods.
/// Storage provides the high-level interface to OpenMLS. A version describes a certain layout of
/// data inside the key-value store.
pub trait Storage<KvStore: Platform> {
    type Stored<T>: Stored<T>;
    /// returns the version of the data currently stored in the KVStore
    fn current_version(&self) -> u16;

    fn apply_update(
        &mut self,
        update: Update,
    ) -> Result<(), UpdateError<KvStore::InternalError, KvStore::SerializeError>>;

    fn apply_updates(
        &mut self,
        updates: Updates,
    ) -> Result<(), UpdateError<KvStore::InternalError, KvStore::SerializeError>> {
        for update in updates.0 {
            self.apply_update(update)?
        }

        Ok(())
    }

    fn get_epoch_key_pairs(
        &self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<
        Vec<Self::Stored<HpkeKeyPair>>,
        GetError<KvStore::InternalError, KvStore::SerializeError>,
    >;

    fn get_encryption_secret_key(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<
        Self::Stored<HpkePrivateKey>,
        GetError<KvStore::InternalError, KvStore::SerializeError>,
    >;

    fn get_init_secret_key(
        &self,
        public_key: &InitKey,
    ) -> Result<
        Self::Stored<HpkePrivateKey>,
        GetError<KvStore::InternalError, KvStore::SerializeError>,
    >;

    fn get_key_package(
        &self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<Self::Stored<KeyPackage>, GetError<KvStore::InternalError, KvStore::SerializeError>>;

    fn get_psk_bundle(
        &self,
        id: &PskBundleId,
    ) -> Result<Self::Stored<PskBundle>, GetError<KvStore::InternalError, KvStore::SerializeError>>;

    // TODO: remove this. Move all state to individual functions
    fn get_mls_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, GetError<KvStore::InternalError, KvStore::SerializeError>>;

    fn get_queued_proposals(
        &self,
    ) -> Result<
        Vec<Self::Stored<StoredProposal>>,
        GetError<KvStore::InternalError, KvStore::SerializeError>,
    >;
}
