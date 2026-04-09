use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorableEncryptionKeyPair<EncryptionKeyPair: Entity<CURRENT_VERSION>>(
    pub EncryptionKeyPair,
);

pub(crate) struct StorableEncryptionKeyPairRef<'a, EncryptionKeyPair: Entity<CURRENT_VERSION>>(
    pub &'a EncryptionKeyPair,
);

pub(crate) struct StorableEncryptionPublicKeyRef<'a, EncryptionPublicKey: Key<CURRENT_VERSION>>(
    pub &'a EncryptionPublicKey,
);

pub(super) struct StorableEpochKeyPairsRef<'a, EpochKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a [EpochKeyPairs],
);

pub(crate) struct StorableKeyPackage<KeyPackage: Entity<CURRENT_VERSION>>(pub KeyPackage);

pub(super) struct StorableKeyPackageRef<'a, KeyPackage: Entity<CURRENT_VERSION>>(
    pub &'a KeyPackage,
);

pub(super) struct StorableHashRef<'a, KeyPackageRef: Key<CURRENT_VERSION>>(pub &'a KeyPackageRef);

pub(crate) struct StorableLeafNode<LeafNode: Entity<CURRENT_VERSION>>(pub LeafNode);

pub(crate) struct StorableLeafNodeRef<'a, LeafNode: Entity<CURRENT_VERSION>>(pub &'a LeafNode);

pub(crate) struct StorableProposal<
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub ProposalRef, pub Proposal);

pub(super) struct StorableProposalRef<
    'a,
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub &'a ProposalRef, pub &'a Proposal);

pub(super) struct StorablePskBundleRef<'a, PskBundle: Entity<CURRENT_VERSION>>(pub &'a PskBundle);

pub(super) struct StorablePskIdRef<'a, PskId: Key<CURRENT_VERSION>>(pub &'a PskId);

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub SignatureKeyPairs,
);

pub(crate) struct StorableSignatureKeyPairsRef<'a, SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a SignatureKeyPairs,
);

pub(super) struct StorableSignaturePublicKeyRef<'a, SignaturePublicKey: Key<CURRENT_VERSION>>(
    pub &'a SignaturePublicKey,
);
