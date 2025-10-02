use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

pub(crate) struct StorableSignatureKeyPairs<SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub SignatureKeyPairs,
);

pub(crate) struct StorableSignatureKeyPairsRef<'a, SignatureKeyPairs: Entity<CURRENT_VERSION>>(
    pub &'a SignatureKeyPairs,
);

pub(super) struct StorableSignaturePublicKeyRef<'a, SignaturePublicKey: Key<CURRENT_VERSION>>(
    pub &'a SignaturePublicKey,
);
