//! Serialization for key store objects.

use crate::{
    credentials::CredentialBundle, key_packages::KeyPackageBundle, schedule::psk::PskBundle,
};

use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};

// === OpenMLS Key Store Types

impl FromKeyStoreValue for KeyPackageBundle {
    type Error = &'static str;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv).map_err(|_| "Invalid key package bundle.")
    }
}

impl FromKeyStoreValue for CredentialBundle {
    type Error = &'static str;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv).map_err(|_| "Invalid credential bundle.")
    }
}

impl ToKeyStoreValue for KeyPackageBundle {
    type Error = &'static str;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self).map_err(|_| "Error serializing key package bundle.")
    }
}

impl ToKeyStoreValue for CredentialBundle {
    type Error = &'static str;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self).map_err(|_| "Error serializing key package bundle.")
    }
}

// PSKs

impl FromKeyStoreValue for PskBundle {
    type Error = &'static str;
    fn from_key_store_value(ksv: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(ksv).map_err(|_| "Invalid PSK bundle.")
    }
}

impl ToKeyStoreValue for PskBundle {
    type Error = &'static str;
    fn to_key_store_value(&self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(self).map_err(|_| "Error serializing PSK bundle.")
    }
}
