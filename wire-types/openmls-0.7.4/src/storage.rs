//! OpenMLS Storage
//!
//! This module serves two purposes:
//!
//! - It implements the Key, Entity and type traits from `openmls_traits::storage::traits`.
//! - It defines traits that specialize the Storage and Provider traits from `openmls_traits`.
//!   This way, the Rust compiler knows that the concrete types match when we use the Provider in
//!   the code.

use openmls_traits::storage::{traits, Entity, Key, CURRENT_VERSION};

/// Bundle used to export a group for migration to a newer OpenMLS version. See
/// [`crate::group::MlsGroup::export_for_migration`].
#[cfg(feature = "migration-export")]
pub use crate::group::GroupMigrationBundle;

use crate::binary_tree::LeafNodeIndex;
use crate::group::proposal_store::QueuedProposal;
use crate::group::{MlsGroupJoinConfig, MlsGroupState};
#[cfg(feature = "extensions-draft-08")]
use crate::schedule::application_export_tree::ApplicationExportTree;
use crate::{
    ciphersuite::hash_ref::ProposalRef,
    group::{GroupContext, GroupId, InterimTranscriptHash},
    messages::ConfirmationTag,
    treesync::{LeafNode, TreeSync},
};
use crate::{
    group::{past_secrets::MessageSecretsStore, GroupEpoch},
    prelude::KeyPackageBundle,
    schedule::{
        psk::{store::ResumptionPskStore, PskBundle},
        GroupEpochSecrets, Psk,
    },
    treesync::{node::encryption_keys::EncryptionKeyPair, EncryptionKey},
};

/// A convenience trait for the current version of the storage.
/// Throughout the code, this one should be used instead of `openmls_traits::storage::StorageProvider`.
pub trait StorageProvider: openmls_traits::storage::StorageProvider<CURRENT_VERSION> {}

/// A convenience trait for the current version of the public storage.
/// Throughout the code, this one should be used instead of `openmls_traits::public_storage::PublicStorageProvider`.
pub trait PublicStorageProvider:
    openmls_traits::public_storage::PublicStorageProvider<
    CURRENT_VERSION,
    PublicError = <Self as PublicStorageProvider>::Error,
>
{
    /// An opaque error returned by all methods on this trait.
    /// Matches `PublicError` from `openmls_traits::storage::PublicStorageProvider`.
    type Error: core::fmt::Debug + std::error::Error;
}

impl<P: openmls_traits::storage::StorageProvider<CURRENT_VERSION>> StorageProvider for P {}

impl<P: openmls_traits::public_storage::PublicStorageProvider<CURRENT_VERSION>>
    PublicStorageProvider for P
{
    type Error = P::PublicError;
}

/// A convenience trait for the OpenMLS provider that defines the storage provider
/// for the current version of storage.
/// Throughout the code, this one should be used instead of `openmls_traits::OpenMlsProvider`.
pub trait OpenMlsProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
    /// The storage to use
    type Storage: StorageProvider<Error = Self::StorageError>;
    /// The storage error type
    type StorageError: std::error::Error;
}

impl<
        Error: std::error::Error,
        SP: StorageProvider<Error = Error>,
        OP: openmls_traits::OpenMlsProvider<StorageProvider = SP>,
    > OpenMlsProvider for OP
{
    type Storage = SP;
    type StorageError = Error;
}

// Implementations for the Entity and Key traits

impl Entity<CURRENT_VERSION> for QueuedProposal {}
impl traits::QueuedProposal<CURRENT_VERSION> for QueuedProposal {}

impl Entity<CURRENT_VERSION> for TreeSync {}
impl traits::TreeSync<CURRENT_VERSION> for TreeSync {}

impl Key<CURRENT_VERSION> for GroupId {}
impl Entity<CURRENT_VERSION> for GroupId {}
impl traits::GroupId<CURRENT_VERSION> for GroupId {}

impl Key<CURRENT_VERSION> for ProposalRef {}
impl Entity<CURRENT_VERSION> for ProposalRef {}
impl traits::ProposalRef<CURRENT_VERSION> for ProposalRef {}
impl traits::HashReference<CURRENT_VERSION> for ProposalRef {}

impl Entity<CURRENT_VERSION> for GroupContext {}
impl traits::GroupContext<CURRENT_VERSION> for GroupContext {}

impl Entity<CURRENT_VERSION> for InterimTranscriptHash {}
impl traits::InterimTranscriptHash<CURRENT_VERSION> for InterimTranscriptHash {}

impl Entity<CURRENT_VERSION> for ConfirmationTag {}
impl traits::ConfirmationTag<CURRENT_VERSION> for ConfirmationTag {}

impl Entity<CURRENT_VERSION> for KeyPackageBundle {}
impl traits::KeyPackage<CURRENT_VERSION> for KeyPackageBundle {}

impl Key<CURRENT_VERSION> for EncryptionKey {}
impl traits::EncryptionKey<CURRENT_VERSION> for EncryptionKey {}

impl Entity<CURRENT_VERSION> for EncryptionKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for EncryptionKeyPair {}

impl Entity<CURRENT_VERSION> for LeafNodeIndex {}
impl traits::LeafNodeIndex<CURRENT_VERSION> for LeafNodeIndex {}

impl Entity<CURRENT_VERSION> for GroupEpochSecrets {}
impl traits::GroupEpochSecrets<CURRENT_VERSION> for GroupEpochSecrets {}

impl Entity<CURRENT_VERSION> for MessageSecretsStore {}
impl traits::MessageSecrets<CURRENT_VERSION> for MessageSecretsStore {}

impl Entity<CURRENT_VERSION> for ResumptionPskStore {}
impl traits::ResumptionPskStore<CURRENT_VERSION> for ResumptionPskStore {}

impl Entity<CURRENT_VERSION> for MlsGroupJoinConfig {}
impl traits::MlsGroupJoinConfig<CURRENT_VERSION> for MlsGroupJoinConfig {}

impl Entity<CURRENT_VERSION> for MlsGroupState {}
impl traits::GroupState<CURRENT_VERSION> for MlsGroupState {}

impl Entity<CURRENT_VERSION> for LeafNode {}
impl traits::LeafNode<CURRENT_VERSION> for LeafNode {}

// Crypto

impl Key<CURRENT_VERSION> for GroupEpoch {}
impl traits::EpochKey<CURRENT_VERSION> for GroupEpoch {}

impl Key<CURRENT_VERSION> for Psk {}
impl traits::PskId<CURRENT_VERSION> for Psk {}

impl Entity<CURRENT_VERSION> for PskBundle {}
impl traits::PskBundle<CURRENT_VERSION> for PskBundle {}

#[cfg(feature = "extensions-draft-08")]
impl Entity<CURRENT_VERSION> for ApplicationExportTree {}
#[cfg(feature = "extensions-draft-08")]
impl traits::ApplicationExportTree<CURRENT_VERSION> for ApplicationExportTree {}
