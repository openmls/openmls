use super::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

// TODO: use newtype or type alias defined elsewhere?
pub type ComponentId = u32;

/// TODO: doc comment
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ComponentData {
    component_id: ComponentId,
    data: VLBytes,
}

impl ComponentData {
    pub fn component_id(&self) -> ComponentId {
        self.component_id
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data.into()
    }
}

/// TODO: doc comment
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ApplicationDataDictionary {
    component_data: Vec<ComponentData>,
}

impl ApplicationDataDictionary {
    pub fn component_data(&self) -> &[ComponentData] {
        &self.component_data
    }
}

/// Application Data Dictionary Extension.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ApplicationDataDictionaryExtension {
    dictionary: ApplicationDataDictionary,
}

impl ApplicationDataDictionaryExtension {
    /// Return the [`ApplicationDataDictionary`] from this extension.
    pub fn dictionary(&self) -> &ApplicationDataDictionary {
        &self.dictionary
    }
}
