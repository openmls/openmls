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
pub struct AppDataDictionary {
    component_data: Vec<ComponentData>,
}

impl AppDataDictionary {
    pub fn component_data(&self) -> &[ComponentData] {
        &self.component_data
    }
}

/// App Data Dictionary Extension.
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
pub struct AppDataDictionaryExtension {
    dictionary: AppDataDictionary,
}

impl AppDataDictionaryExtension {
    /// Return the [`AppDataDictionary`] from this extension.
    pub fn dictionary(&self) -> &AppDataDictionary {
        &self.dictionary
    }
}
