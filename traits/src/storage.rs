use serde::{de::DeserializeOwned, Serialize};

pub trait GetError: core::fmt::Debug + std::error::Error + PartialEq {
    fn error_kind(&self) -> GetErrorKind;
}

pub trait UpdateError: core::fmt::Debug + std::error::Error + PartialEq {
    fn error_kind(&self) -> UpdateErrorKind;
}

pub trait StorageProvider<const VERSION: u16> {
    // source for errors
    type GetError: GetError;
    type UpdateError: UpdateError;

    // Write/queue
    fn queue_proposal(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        proposal_ref: impl ProposalRefEntity<VERSION>,
        proposal: impl QueuedProposalEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_tree(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        tree: impl TreeSyncEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_interim_transcript_hash(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        interim_transcript_hash: impl InterimTranscriptHashEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_context(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        group_context: impl GroupContextEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_confirmation_tag(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        confirmation_tag: impl ConfirmationTagEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_signature_key_pair(
        &self,
        public_key: impl SignaturePublicKeyKey<VERSION>,
        signature_key_pair: impl SignatureKeyPairEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_hpke_private_key(
        &self,
        public_key: impl InitKey<VERSION>,
        private_key: impl HpkePrivateKey<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_key_package(
        &self,
        hash_ref: impl HashReference<VERSION>,
        key_package: impl KeyPackage<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_psk(
        &self,
        psk_id: impl PskKey<VERSION>,
        psk: impl PskBundle<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_encryption_key_pair(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
        key_pair: impl HpkeKeyPair<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    // getter
    fn get_queued_proposal_refs<V: ProposalRefEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<Vec<V>, Self::GetError>;

    fn get_queued_proposals<V: QueuedProposalEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<Vec<V>, Self::GetError>;

    fn get_treesync<V: TreeSyncEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn get_group_context<V: GroupContextEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn get_interim_transcript_hash<V: InterimTranscriptHashEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn get_confirmation_tag<V: ConfirmationTagEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    // Get crypto objects

    fn signature_key_pair<V: SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn hpke_private_key<V: HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl InitKey<VERSION>,
    ) -> Result<V, Self::GetError>;
    fn key_package<V: KeyPackage<VERSION>>(
        &self,
        hash_ref: impl HashReference<VERSION>,
    ) -> Result<V, Self::GetError>;
    fn psk<V: PskBundle<VERSION>>(&self, psk_id: impl PskKey<VERSION>)
        -> Result<V, Self::GetError>;
    fn encryption_key_pair<V: HpkeKeyPair<VERSION>>(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
    ) -> Result<V, Self::GetError>;
}

// base traits for keys and values
pub trait Key<const VERSION: u16>: Serialize {}
pub trait Entity<const VERSION: u16>: Serialize + DeserializeOwned {}

// in the following we define specific traits for Keys and Entities. That way
// we can don't sacrifice type safety in the implementations of the storage provider.
// note that there are types that are used both as keys and as entities.

// traits for keys, one per data type
pub trait GroupIdKey<const VERSION: u16>: Key<VERSION> {}
pub trait ProposalRefKey<const VERSION: u16>: Key<VERSION> {}
pub trait SignaturePublicKeyKey<const VERSION: u16>: Key<VERSION> {}
pub trait InitKey<const VERSION: u16>: Key<VERSION> {}
pub trait HashReference<const VERSION: u16>: Key<VERSION> {}
pub trait PskKey<const VERSION: u16>: Key<VERSION> {}
pub trait HpkePublicKey<const VERSION: u16>: Key<VERSION> {}

// traits for entity, one per type
pub trait QueuedProposalEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait ProposalRefEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait TreeSyncEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait GroupContextEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait InterimTranscriptHashEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait ConfirmationTagEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait SignatureKeyPairEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait HpkePrivateKey<const VERSION: u16>: Entity<VERSION> {}
pub trait KeyPackage<const VERSION: u16>: Entity<VERSION> {}
pub trait PskBundle<const VERSION: u16>: Entity<VERSION> {}
pub trait HpkeKeyPair<const VERSION: u16>: Entity<VERSION> {}

// errors
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetErrorKind {
    NotFound,
    Encoding,
    Internal,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpdateErrorKind {
    Encoding,
    Internal,
    LockPoisoned,
    AlreadyExists,
}
