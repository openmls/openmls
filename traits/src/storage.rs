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

    // Write crypto objects

    /// Store a signature key.
    ///
    /// Note that signature keys are defined outside of OpenMLS.
    fn write_signature_key_pair(
        &self,
        public_key: impl SignaturePublicKeyKey<VERSION>,
        signature_key_pair: impl SignatureKeyPairEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store an HPKE init private key.
    ///
    /// This is used for init keys from key packages.
    fn write_init_private_key(
        &self,
        public_key: impl InitKey<VERSION>,
        private_key: impl HpkePrivateKey<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store an HPKE encryption key pair.
    /// This includes the private and public key
    ///
    /// This is used for encryption keys from leaf nodes.
    fn write_encryption_key_pair(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
        key_pair: impl HpkeKeyPair<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store key packages.
    ///
    /// Store a key package. This does not include the private keys. They are
    /// stored separately with `write_hpke_private_key`.
    fn write_key_package(
        &self,
        hash_ref: impl HashReference<VERSION>,
        key_package: impl KeyPackage<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store a PSK.
    ///
    /// This stores PSKs based on the PSK id.
    fn write_psk(
        &self,
        psk_id: impl PskKey<VERSION>,
        psk: impl PskBundle<VERSION>,
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

    /// Get a signature key based on the public key.
    fn signature_key_pair<V: SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get a private init key based on the corresponding public kye.
    fn init_private_key<V: HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl InitKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get an HPKE encryption key pair based on the public key.
    fn encryption_key_pair<V: HpkeKeyPair<VERSION>>(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get a key package based on its hash reference.
    fn key_package<V: KeyPackage<VERSION>>(
        &self,
        hash_ref: impl HashReference<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get a PSK based on the PSK identifier.
    fn psk<V: PskBundle<VERSION>>(&self, psk_id: impl PskKey<VERSION>)
        -> Result<V, Self::GetError>;

    // Delete crypto objects

    /// Delete a signature key pair based on its public key
    fn delete_signature_key_pair<V: SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Delete an HPKE private init key.
    ///
    /// XXX: This should be called when deleting key packages.
    fn delete_hpke_private_key<V: HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl InitKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Delete an encryption key pair for a public key.
    fn delete_encryption_key_pair<V: HpkeKeyPair<VERSION>>(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Delete a key package based on the hash reference.
    ///
    /// XXX: This needs to delete all corresponding keys.
    fn delete_key_package<V: KeyPackage<VERSION>>(
        &self,
        hash_ref: impl HashReference<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Delete a PSK based on an identifier.
    fn delete_psk<V: PskBundle<VERSION>>(
        &self,
        psk_id: impl PskKey<VERSION>,
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
