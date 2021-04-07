use crate::{credentials::CredentialError, key_packages::KeyPackageError};

implement_error! {
   pub enum KeyStoreError {
       Simple {
           NoMatchingCredentialBundle = "No `CredentialBundle` found for the given `Credential`.",
           NoMatchingKeyPackageBundle = "No `KeyPackageBundle` found for the given `KeyPackage` hash.",
       }
       Complex {
           KeyPackageError(KeyPackageError) = "Error while creating `KeyPackageBundle`. See [`KeyPackageError`](`crate::key_packages::KeyPackageError`) for details.",
           CredentialError(CredentialError) = "Error while creating `CredentialBundle`. See [`CredentialError`](`crate::credentials::CredentialError`) for details.",
       }
    }
}
