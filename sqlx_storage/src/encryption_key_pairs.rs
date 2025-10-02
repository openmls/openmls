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
