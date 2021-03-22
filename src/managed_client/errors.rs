use crate::group::ManagedGroupError;
use crate::key_store::KeyStoreError;

implement_error! {
    pub enum ManagedClientError {
        Simple {
            DuplicateGroupId = "A group with this GroupId already exists.",
            NoMatchingGroup = "No group with the given GroupId was found.",
            UnsupportedCiphersuite = "The given ciphersuite is not supported by the library.",
            NoCiphersuiteProvided = "No ciphersuites were provided to generate a `KeyPackage`.",
            PoisonError = "An error ocurred when attempting to obtain a lock on an internal variable. See [`PoisonError`](`std::sync::PoisonError`) for details.",
            ReadError = "Error while reading a persisted group.",
            WriteError = "Error while persisting a group.",
        }
        Complex {
            KeyStoreError(KeyStoreError) = "An error occurred while accessing the `KeyStore`. See [`KeyStoreError`](`crate::key_store::KeyStoreError`) for details.",
            ManagedGroupError(ManagedGroupError) = "An error occurred when operating on a `ManagedGroup`. See [`ManagedGroupError`](`crate::group::ManagedGroupError`) for details.",
        }
    }
}
